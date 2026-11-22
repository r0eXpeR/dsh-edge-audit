---
name: dsh-edge-report
description: 输出有来源、证据分级和可复现边界的安全报告；适用于审计结论、漏洞写作与导出。
---

# 输出有来源、证据分级和可复现边界的安全报告；适用于审计结论、漏洞写作与导出

从 canonical Findings 和 receipt 生成报告，区分 confirmed、needs_validation、rejected、duplicate、修复复验及覆盖缺口。清楚标明 statically_validated 与 runtime_validated，不把静态路径写成已成功利用。

包含受影响代码、根因、攻击者与权限、完整路径、前提、影响、反证、证据限制及最小有效修复。复现步骤和 HTTP/Burp 报文只在接口、参数、配置和所用假数据有来源时给出；未执行的请求标注“待验证示例”，不用虚构响应、真实凭据、生产地址或成功截图填补空白。非 HTTP 接口使用其真实 CLI、库调用、消息或文件协议，不强凑 Burp 请求。

报告脱敏保留行号与摘要，链接保留产物。大记录通过分页详情和导出读取，不将被截断文本当成完整 JSON。失败写明阶段、可操作原因和原恢复 ID。只有真实外部回读成功才能说已创建工单或披露。

方法改编自本地 Codex Security 0.8.0、Cloudflare security-audit-skill 与 Anthropic claude-code-security-review；宿主工具、状态和安全边界以 DSH 插件实现为准。许可见包内 NOTICE 与 docs/licenses。
