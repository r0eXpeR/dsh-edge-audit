<!-- 改编自 Cloudflare security-audit-skill SUPPLY-CHAIN-AND-RELEASE.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/supply-chain.md -->

# 供应链与发布

## 核心方法

适用：目标解析依赖、构建不可信贡献、运行 CI、产出发布物、签名或晋升构建、加载插件、更新已部署软件。覆盖从源码、依赖到用户实际运行产物的信任交接。本地 binary loader 缺陷见 native-memory，运行时 workload 权限见 cloud。大型目标拆为依赖解析、CI 隔离、制品来源、发布授权、updater/插件信任。

- 可变或已知有漏洞的依赖本身不是发现。要说明谁能影响解析、哪个构建消费它、随后跨越什么执行或发布边界。
- 沿每次交接追完整性：源码身份、解析后的输入、构建 worker、制品身份、测试结果、签名/attestation、晋升、更新消费者。
- CI 配置就是授权代码。确定哪个事件触发 workflow、运行谁的代码、有哪些 secret 和 token、能发布或变更什么。
- 与制品同一不可信位置取得的 checksum 不构成独立完整性。指出 trusted root 和失败行为。
- 从已发布 digest 或已安装更新反向走到每个源码、生成输入、凭据、worker、cache、测试结果、授权决策。
- 并排比较不可信和受保护 workflow 事件，标出跨越两者的每条持久化通道，要求不可变身份和 producer 信任。
- 审查 key 吊销、下载失败、缺 attestation、部分平台发布、rollback、registry 中断路径。失败策略是发布完整性的一部分。

## 类目检查点

### 依赖与构建输入
- **依赖来源/namespace 混淆**：resolver 配置可选中非预期的公共/私有 namespace、fallback registry、mirror、仓库或 source URL。查包名、source 优先级、lockfile 与 checksum 使用、备用构建文件、平台相关解析、首次安装与更新的差异。
- **可变、未绑定的构建输入**：构建消费分支、tag、未验证 submodule、下载的工具、生成资产、remote include、浮动 CI action、容器 tag，内容可不经审查改变。需要低信任写入者和进入可信构建输出的路径；可复现性本身不证明真实性。
- **生成代码来源缺口**：schema、vendored 归档、生成 client、本地化、文档示例、二进制 blob 产出可执行或发布内容，却未走与源码相同的审查和完整性闸门。比较本地再生成与提交内容，核实谁控制输入和生成器。
- **构建上下文混入**：secret、本地配置、仓库元数据、测试 fixture、开发者产物因 build context 和 ignore 规则过宽进入包或镜像。确认最终制品暴露真实凭据、私有数据或特权配置。

### CI 与自动化
- **特权 workflow 运行不可信代码**：PR、issue comment、fork、依赖更新、外部事件以受保护 secret、写 token、部署权限或可信 runner 运行贡献者代码。比较 trigger 类型（如 `pull_request_target`）、checkout ref、审批闸门、environment 保护、permission 收窄。不要假设源码外的仓库托管默认值。
- **Workflow 命令/表达式混淆**：分支名、commit message、issue 字段、artifact 名、matrix 值、生成输出未经规范校验进入 shell 命令、模板表达式、路径或特权 workflow 输入。
- **Cache、artifact、workspace 信任混用**：低信任 job 写入 cache、artifact、共享 workspace 或 output，高信任 job 随后恢复并执行或发布。查 cache key 与 namespace、artifact producer 身份、digest 绑定、retention，晋升是否按可变名称重新解析。
- **自动化身份越权**：CI job 权限超出操作、仓库、environment、时长所需，且不可信 job 输入可选择受影响资源。单缺最小权限是加固项，需可达特权动作。

### 发布与更新
- **Build→promotion 替换**：测试、审查、签名、发布引用可变 tag、文件名、channel、artifact ID，而非同一不可变 digest。查构建到发布之间每次 copy、repack、架构合并、provenance 步骤。
- **发布授权与签名策略缺口**：接受来自错误 workflow、仓库、分支、environment、key 角色或阈值的发布或签名。审查 attestation 内身份声明，核实消费者校验这些声明而非仅“签名有效”。rotation、expiry、revocation 在策略要求处必须 fail closed。
- **更新元数据与 rollback 混淆**：updater 认证 payload 字节，但不认证 version、product、platform、channel、目标路径、expiry、rollback 状态，或接受来自不同授权事务的 metadata 与 payload。核实原子安装和恢复。调用签名 API 却无策略绑定是不完整的。
- **插件/扩展信任扩张**：扩展包获得超出声明范围的宿主权限，低信任 publisher 可替换他人身份，install/update hook 在真实性和能力检查前运行。同用户有意安装任意插件不是特权边界。

## 验证与反证

1. 写出低信任 actor、可控的 source/cache/artifact/metadata、消费它的可信 job 或 updater，以及未授权发布、代码混入、secret 泄露或特权执行结果。
2. 证明被破坏交接处的制品身份：不同的可变名称或未绑定 digest 确实到达真实消费者。
3. 核实所用版本的包管理器、仓库托管、registry、签名默认值。未知的托管控制（branch protection、hosted runner、registry、签名服务、生产晋升）记 Needs Validation，写明所有者需观察的确切事实。
4. 本地验证保持有界：无害 fixture 仓库、假凭据标记、本地 registry/配置、非生产 artifact namespace。绝不发布或改动真实发布物。
5. **常见误报**：只报过期依赖或 CVE 而无可达路径；只报未 pin 版本而无低信任写入者；只报权限过宽而无可达特权动作；`pull_request` 不带 secret 的 fork 流程；签名 checksum 与制品同源但已有独立 trusted root；同用户安装任意插件；私有内部依赖不在公共 registry 本身不算，需证明解析真的可落到攻击者控制的 namespace。
6. 确认需完整的源码可见交接和有意义结果；仓库内控制流失败可由有界本地验证确认。
