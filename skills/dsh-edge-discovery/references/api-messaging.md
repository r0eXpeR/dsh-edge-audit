<!-- 改编自 Cloudflare security-audit-skill PROTOCOLS-RPC-AND-MESSAGING.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/api-messaging.md -->

# 协议、RPC 与消息

## 核心方法

适用：gRPC、GraphQL transport、Cap'n Proto、Thrift、Protobuf、自定义二进制协议、streaming RPC、webhook、broker、queue、pub/sub、event bus。关注 peer 身份、逻辑消息解释、路由、replay、顺序和投递语义。parser 内存安全见 native-memory，HTTP framing 见 web-auth，可用性影响见 resources。大型系统按 producer/consumer 对、外部/内部 peer 角色、同步 RPC、streaming、异步消息路径拆分。

- “内部”不是认证。写出每一跳的 peer 身份，并说明它如何变成授权使用的应用 principal。
- Schema 校验只证明消息形状，不证明来源、资源权限、顺序或值安全。把解码字段追到策略与副作用。
- Broker 保证与应用保证不同。评估状态变更前先写下 retry、ordering、ack、dedup、事务行为。
- Parser 分歧需要两个具体 consumer、schema 版本或 wire 表示，以及一个安全相关的分歧值。
- 对每个消息族画 producer → broker/transport → gateway → consumer → storage，每跳记录已认证 peer、权威 tenant/resource 字段、校验、副作用。
- 给仓库内每个 schema 版本或语言 binding 喂同一个小 fixture，测试重复、缺失、未知、边界、重放、乱序消息，不制造负载。
- 比较 normal、retry、dead-letter、replay、migration、reflection、stream、gateway-transcoded 路由；安全策略必须在传输变化后仍然成立。

## 类目检查点

### Framing、schema 与解释
- **消息边界与 canonicalization 分歧**：组件对长度、压缩、重复字段、未知字段、编码、数值宽度、归一化、envelope/body 优先级看法不同。比较生成与自研 parser、gateway、语言 binding、版本转换器，确认解码后哪个 principal、resource 或操作不同。
- **Union、enum、默认值混淆**：未知 variant、缺 discriminator、零值、默认权限或兼容映射到达假定已校验分支的代码。查穷举 dispatch、default 分支、旧 consumer 如何解释新增字段。
- **Envelope 与 payload 身份不一致**：授权使用看似可信的路由或 envelope 元数据，handler 却按 body 中冲突的 tenant、account、subject、object、sender 行动。确定哪个来源权威，客户端不能覆盖。

### RPC 身份与授权
- **Interceptor 与方法路径不一致**：authn/authz interceptor 覆盖 unary，但漏掉 stream、reflection、health、gateway transcoding 路径、兼容服务或单条 stream 消息。比较到达同一操作的每个注册与路由。
- **Peer 身份到应用 principal 混淆**：mTLS、workload identity、bearer metadata、转发身份、broker 凭据认证了 channel，却由调用方字段选择 user 或 tenant。channel 身份与声称 principal 必须由确定性策略绑定。
- **逐项与 streaming 授权缺口**：stream、subscription、batch、bulk 消息只授权一次，后续项指向不同资源，或在角色、成员资格、token 撤销后继续。scope 可变处要复查，subscription 绑定原 principal。
- **Callback 与 reply 关联混淆**：可预测、重用或跨租户的 correlation ID 让响应、webhook、取消、ack 满足他人的 pending 操作。每个未完成请求绑定已认证 peer、tenant、操作、生命周期。

### Broker 与 queue 隔离
- **Topic、routing key、subscription 范围**：publisher/subscriber 可选他人的 topic、wildcard、consumer group、partition、reply queue、dead-letter 路由。查可见的 broker ACL 和应用侧 namespace 构造；payload 内的租户文本不是隔离。
- **Dead-letter、retry、诊断泄露**：进入 DLQ、错误 topic、tracing、运维视图的消息含 secret 或跨租户 payload，被低信任 consumer 访问。查失败路径上的策略与脱敏，不止正常投递。
- **不可信 producer 被当控制面**：消息体可自称 admin event、provider callback、replication record、migration 指令，而 producer 和事件类型没有独立认证。特权处理前核实签名和 source/account/audience 绑定。Webhook 同理。

### Replay、顺序与事务
- **重复投递与幂等缺口**：retry/redelivery 重复副作用，因为无 dedup、dedup 在变更之后、或 key 跨租户/操作碰撞。确认 broker 投递模型和非天然幂等的副作用。
- **乱序与陈旧消息**：旧状态、已撤销成员资格、已取消工作、step-up 前的授权在较新状态后到达并覆盖。查 sequence/version、tombstone、partition 变更、restore/replay 流程。
- **Ack/commit 顺序缺陷**：先 ack 后 durable commit 丢失安全相关工作，或先 commit 后不可靠 ack 重复变更。评估 transactional outbox/inbox 与故障恢复。
- **多 consumer 部分迁移**：多个 consumer 共同实现一次授权或业务迁移，retry 与部分失败后只提交子集。找出必须原子持久化或以当前授权补偿的不变量。

## 验证与反证

1. 写出现实的 producer 或 peer、被接受消息、已认证 channel 身份、受影响 principal/resource、越权变更或泄露。
2. 分歧主张要引用两个 parser/consumer 及解码分歧值。任一侧安全拒绝即不能确认。
3. Replay/顺序主张要先确定实际投递保证，再用有界本地或内存 transport 复现不变量失败。
4. 授权与隔离要核实源码可见的 interceptor、broker ACL、gateway、consumer 所有层。外部挂载（broker ACL、mesh 身份、topic attachment、兼容行为）决定结论时记 Needs Validation，写明确切的 broker、服务身份、路由或投递事实。
5. **常见误报**：把 schema 校验当授权的反向论证同样不成立；“内部接口”不是反证，也不是证据，要看 peer 身份；天然幂等的副作用不构成重复投递问题；单纯消息格式宽松但无安全相关分歧值不成立；payload 含 tenant 字段不等于已隔离，也不等于已串租户，需找到实际 namespace 构造。
6. 确认需完整消息生命周期和观察到的有意义结果；不足时保留决定性缺口。
