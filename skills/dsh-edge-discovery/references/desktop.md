<!-- 改编自 Cloudflare security-audit-skill DESKTOP-MOBILE-AND-LOCAL-IPC.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/desktop.md -->

# 桌面、移动端与本地 IPC

## 核心方法

适用：桌面或移动应用、特权 helper、updater、本地 daemon、webview host、deep-link handler、浏览器 native-messaging host、本地 IPC client/server。不可信 actor 可能是下载的文档、远程 Web 内容、另一本地应用、另一 OS 用户、沙箱进程或低权限账号。要写明起始能力，不把所有本地用户视为同等。浏览器侧 webview 行为见 client，native 内存与 loader 安全见 native-memory，更新真实性见 supply-chain。

- 确定现实的本地或远程内容攻击者。同账号同权限内的自伤不是边界违规。
- 路径、进程名、bundle/package ID、声称的 sender 字段不是 peer 认证。应使用 OS peer credential、code identity、capability handle 或受保护的 channel 状态。
- Native bridge 或 helper 必须在解析后对每个操作和最终资源授权。可信 UI 或 broker 不会让攻击者可影响的参数变可信。
- OS 沙箱、签名、entitlement、permission、keychain ACL、exported 组件策略、prompt 行为，在版本固定且可见时是真实控制。
- 枚举每个进程、应用组件、本地 endpoint、URI scheme、文件关联、webview origin、helper，记录 OS 身份、运行权限、调用方、可调用操作。
- 读最终打包输入：合并后 manifest、entitlement、安装规则、native-messaging 注册、protocol handler、ACL 创建。源码声明可能被下游覆盖。
- 用假 profile 和非敏感本地 fixture 在隔离机器/emulator 上验证，不接触他人应用、凭据或生产服务。

## 类目检查点

### Deep link、callback 与导航
- **Custom scheme/deep link 歧义**：其他应用或页面可调用能变更状态、导入数据、完成认证、选择账号的路由，缺当前 session 和一次性 callback 绑定。查 URI 归一化、重复 query 字段、scheme/host/path 匹配、exported activity/handler 策略、过期或重放链接。
- **应用与账号交接混淆**：OAuth、SSO、magic link、邀请、设备配对、passwordless、支付 callback 回到错误的已安装应用、profile、租户或待处理事务。state 绑定发起应用身份、当前 session、账号、provider、操作、expiry。
- **文件打开与 intent 权限混淆**：关联文件、share intent、拖放项、剪贴板记录、通知动作、open-file 事件触发特权操作，未确认内容类型、适用时的 sender 信任、当前用户意图、最终目标。

### Webview 与 native bridge
- **导航 origin 到 bridge 混淆**：远程或攻击者控制的 frame 可触及仅为打包内容设计的 JavaScript/native bridge。在调用时，以及每次导航、重定向、subframe 创建、popup、错误/fallback 页后校验 origin。URL 前缀检查和仅初次加载检查都不够。
- **Native bridge 能力过宽**：Web 内容经通用 bridge 选择任意文件、命令、IPC 方法、凭据、系统动作。查方法 allowlist、归一化参数、用户/租户权限、手势/确认要求、返回值泄露。
- **Webview 文件与 universal access**：远程内容可读应用本地文件、特权 custom scheme、内部 origin，因为 file access、universal access、mixed content、debug 接口、自定义 protocol handler 意外连通 origin。缺限制设置但无可达受保护内容是加固项。

### 本地 IPC 与 exported 组件
- **IPC peer 认证缺口**：Unix socket、named pipe、XPC、Binder、D-Bus、native messaging、RPC、共享内存、loopback listener 接受低信任 peer，未查 OS 凭据、code identity、沙箱 token、channel 归属。需要 channel 后有有意义的方法或泄露。
- **声称 principal 与 channel 身份不一致**：已认证进程/channel 属于一个应用或用户，请求字段却选另一用户、租户、profile、能力。每个方法和资源绑定 peer credential，而非调用方声明的标识符。
- **Exported service/activity/receiver/provider 越权**：移动组件或本地自动化 endpoint 可被外部调用，执行本应应用自用的操作。查合并后 manifest、intent filter、permission/signature 级别、path grant、备用 alias。打包后 manifest 状态未知记 Needs Validation。
- **IPC 生命周期与关联混淆**：可预测 request ID、重用 handle、陈旧 channel、继承 descriptor、world-writable socket 路径、重启行为，让一个 peer 回答、取消或重用另一 peer 的操作。查 socket 文件、lock、端口、共享映射的创建权限和清理。

### 特权 helper 与本地文件
- **特权 helper 作 confused deputy**：低权限调用方可选特权命令、文件、服务、用户、系统设置，缺逐操作授权。审查 sudo/polkit/UAC/XPC helper 规则，helper 须独立校验归一化参数。
- **安装、更新、修复路径信任**：特权 installer/helper 在授权后读取低信任 actor 可写的 manifest、脚本、包、symlink、工作目录、repair 状态。授权绑定不可变内容和安全目标路径。
- **本地文件归属与 TOCTOU**：先检查 file/path，随后特权读写跟随替换、symlink、mount、大小写/归一化变化。用 descriptor-relative 操作并核实最终归属。
- **凭据存储与本地 secret 边界不匹配**：keychain/keystore 项、token 文件、backup、日志、剪贴板、通知预览、本地配置被权限更低的其他应用/profile/用户读取。仅同一预期 OS 账号可读的明文不自动算漏洞；写明低信任读者和凭据权力。

### 应用状态与设备生命周期
- **账号切换、logout、设备恢复泄漏**：缓存数据、后台任务、widget、通知、本地数据库、webview 存储、生物识别批准在 logout/换账号后存活并出现在后续账号。查 backup/restore 和多 profile。
- **待处理动作与用户在场混淆**：通知、widget、shortcut、share sheet、生物识别 prompt、延迟操作授权的动作与显示不同、过期后执行或使用其他 profile 的待处理状态。确认绑定归一化动作、资源、账号、当前前台状态。

## 验证与反证

1. 写出攻击者起始能力、被跨越的 OS/应用 principal、入口 channel、被接受的参数或状态、越权操作或泄露。
2. 确认适用的 OS 沙箱、peer credential、签名、entitlement、permission、用户同意、安装控制。未知的打包/运行事实记 Needs Validation。
3. Webview bridge 同时引用导航/origin 控制和特权 native sink；IPC 引用 peer 认证和逐资源授权；helper 核实最终归一化目标。
4. 本地测试保持有界并用假内容/账号，证明边界结果后即停，不延伸到持久化或更广系统修改。
5. **常见误报**：同账号同权限的自伤；同一 OS 用户可读的明文；用户加载自己的插件；缺限制设置但无可达受保护内容；需已具 root/admin 的前提且无权限增量；manifest 声明已被打包流程覆盖。
6. 确认需完整源码和本地证据链；否则记 Needs Validation，写明确切的 OS、manifest、签名、ACL 或设备生命周期事实。
