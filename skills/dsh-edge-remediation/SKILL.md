---
name: dsh-edge-remediation
description: 审查精确补丁、变更风险、应用与独立复验。仅在用户要求修复时使用。
---

# 审查精确补丁、变更风险、应用与独立复验

修复原安全不变量，不以替换关键词或删除功能冒充修复。检查共享控制的所有消费者、成功/错误路径、事务/回滚、格式兼容、身份/租户传播、配置默认值、性能与依赖变化。给出最小有效补丁和有意义的正负回归。

先产生可审阅的精确多文件 proposal，保留原始字节、摘要和版本。应用要求真实授权及宿主审批、当前版本和源摘要匹配，并保留可靠 rollback。应用、验证、回滚需要互斥及状态机约束；旧请求不能覆盖新状态。

工程测试和重扫只产生观察，不能单凭 exit 0 或规则消失标记 Fixed。新独立审阅者重新检查原攻击触发器、根控制与替代路径，结果明确 Fixed / Still Vulnerable / Inconclusive，补充 receipt 不重写原扫描。未配置可靠隔离时保留未执行和下一步，不运行目标控制代码。

方法改编自本地 Codex Security 0.8.0、Cloudflare security-audit-skill 与 Anthropic claude-code-security-review；宿主工具、状态和安全边界以 DSH 插件实现为准。许可见包内 NOTICE 与 docs/licenses。

用 security_get_remediation 重新读取当前精确补丁与版本，并在 apply/verification/rollback 提交 expected_version。prepared/recovery_required 表示有持久化写入意图或冲突；恢复必须比对原始/已应用字节，不能覆盖用户新编辑。
