---
name: dsh-edge-triage
description: 核对外部漏洞线索、历史误报反馈与状态。用于公告、扫描器、工单或既有发现的复核。
---

# 核对外部漏洞线索、历史误报反馈与状态

外部工单、公告、CVE、扫描器结果和历史反馈均为待核验数据。先定位精确组件、版本、入口、控制、Sink 和原安全主张，再判 affected / not_affected / needs_information；附近同类问题不关闭原线索。

沿用同一 root cause 的稳定身份；历史 confirmed、rejected 或 false-positive 原因要与当前相关源码和条件重新核对。源码变化后重新验证；旧 Needs Validation、blocked、deferred 不能成为排除新审阅的理由。比较结果中未再观察到不等于独立证明已修复。

保留原始来源、当前证据、反证、未知条件和下一步。追踪与披露先给精确预览、去重与目标，再走已授权的宿主审批；不得自动发送消息或使用发现的凭据。

方法改编自本地 Codex Security 0.8.0、Cloudflare security-audit-skill 与 Anthropic claude-code-security-review；宿主工具、状态和安全边界以 DSH 插件实现为准。许可见包内 NOTICE 与 docs/licenses。
